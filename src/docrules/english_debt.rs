//! `stenio language`: the translation debt ledger and the loop that pays it down.
//!
//! `report` totals the debt, `--init` and `--prune` write the ledger (the line baseline of
//! `LANG-ENGLISH-REQUIRED`, which only shrinks), `next` hands out one batch of files with a claim
//! so two agents do not collide, and `verify` proves a translation kept the structure of the
//! document, left no Portuguese behind, and only then lowers the ledger.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

use regex::Regex;

use super::Ctx;
use super::english_required::{
    Hit, Scope, collect, git, judge_message, line_hash, portuguese_lines, read_baseline, relative,
};

/// A claim older than this is abandoned and may be taken again.
const CLAIM_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const DEFAULT_BUDGET: usize = 150;
const TIERS: [&str; 4] = ["1-rules", "2-runbooks", "3-other", "4-personal"];

/// The translation priority of a file: agent rule files, runbooks, the rest, personal notes.
fn tier(rel: &str) -> usize {
    let lower = rel.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    let under = |dir: &str| lower.starts_with(dir) || lower.contains(&format!("/{dir}"));
    if under("personal/") || under("temp/") || under("archive/") || name.contains("archive") {
        3
    } else if ["agents.md", "claude.md", "skill.md", "soul.md"].contains(&name)
        || under("scripts/agent-hooks/")
        || (under("governance/") && !name.starts_with("backlog"))
    {
        0
    } else if under("guides/")
        || under("services/")
        || under("servers/")
        || under("docs/")
        || name.contains("runbook")
        || name == "readme.md"
    {
        1
    } else {
        2
    }
}

/// Deterministic ledger text: totals, one comment line per file, then the line hashes. With
/// `keep`, an entry never exceeds its previous count, so the ledger cannot grow.
fn render(root: &Path, hits: &[Hit], keep: Option<&HashMap<u64, usize>>) -> String {
    let mut left = keep.cloned();
    let mut entries: BTreeMap<u64, (usize, String)> = BTreeMap::new();
    let mut files: BTreeMap<String, usize> = BTreeMap::new();
    for hit in hits {
        let hash = line_hash(&hit.text);
        if let Some(left) = left.as_mut() {
            match left.get_mut(&hash) {
                Some(n) if *n > 0 => *n -= 1,
                _ => continue,
            }
        }
        let file = relative(root, &hit.path);
        *files.entry(file.clone()).or_default() += 1;
        entries.entry(hash).or_insert((0, file)).0 += 1;
    }
    let mut tiers = [0usize; 4];
    for (file, n) in &files {
        tiers[tier(file)] += n;
    }
    let mut text = format!(
        "# stenio language ledger: existing Portuguese debt. It only shrinks; never edit by hand.\n# total lines={} files={}",
        tiers.iter().sum::<usize>(),
        files.len()
    );
    for (name, n) in TIERS.iter().zip(tiers) {
        text.push_str(&format!(" {name}={n}"));
    }
    text.push('\n');
    for (file, n) in &files {
        let area = file.split_once('/').map_or(".", |(a, _)| a);
        text.push_str(&format!("# file {n} {} {area} {file}\n", TIERS[tier(file)]));
    }
    for (hash, (count, file)) in entries {
        text.push_str(&format!("{hash:016x} {count} {file}\n"));
    }
    text
}

fn per_file<'a>(root: &Path, hits: &'a [Hit]) -> BTreeMap<String, Vec<&'a Hit>> {
    let mut files: BTreeMap<String, Vec<&Hit>> = BTreeMap::new();
    for hit in hits {
        files
            .entry(relative(root, &hit.path))
            .or_default()
            .push(hit);
    }
    files
}

fn summary(scope: &Scope, hits: &[Hit]) -> String {
    let files = per_file(&scope.root, hits);
    let mut tiers = [0usize; 4];
    for (file, lines) in &files {
        tiers[tier(file)] += lines.len();
    }
    let mut line = format!(
        "language debt {}: {} line(s) in {} file(s)",
        scope.root.display(),
        hits.len(),
        files.len()
    );
    for (name, n) in TIERS.iter().zip(tiers) {
        line.push_str(&format!(" {name}={n}"));
    }
    line
}

/// One line per ledgered tree under `target`, for the routine reports. A tree that declares no
/// ledger prints nothing, so reports of other trees stay as they were.
pub fn totals(target: &Path) -> Vec<String> {
    collect(&Ctx::new(target, None))
        .values()
        .filter(|(scope, _)| scope.baseline.is_some())
        .map(|(scope, hits)| summary(scope, hits))
        .collect()
}

fn claim_dir(scope: &Scope) -> PathBuf {
    match &scope.baseline {
        Some(file) => file.with_extension("claims"),
        None => scope.root.join(".stenio-language-claims"),
    }
}

fn claim_file(scope: &Scope, rel: &str, kind: &str) -> PathBuf {
    claim_dir(scope).join(format!("{:016x}.{kind}", line_hash(rel)))
}

fn claimed(scope: &Scope, rel: &str) -> bool {
    fs::metadata(claim_file(scope, rel, "claim"))
        .and_then(|m| m.modified())
        .is_ok_and(|t| {
            SystemTime::now()
                .duration_since(t)
                .map_or(true, |age| age < CLAIM_TTL)
        })
}

/// Takes the file for `agent` and keeps its original for `verify`. False when someone holds it.
fn claim(scope: &Scope, rel: &str, agent: &str) -> std::io::Result<bool> {
    if claimed(scope, rel) {
        return Ok(false);
    }
    fs::create_dir_all(claim_dir(scope))?;
    let mark = claim_file(scope, rel, "claim");
    if mark.exists() {
        fs::remove_file(&mark)?;
    }
    let mut file = match fs::File::options().write(true).create_new(true).open(&mark) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e),
    };
    std::io::Write::write_all(&mut file, format!("{agent}\n{rel}\n").as_bytes())?;
    fs::copy(scope.root.join(rel), claim_file(scope, rel, "orig"))?;
    Ok(true)
}

/// The next batch: whole files in priority order until the line budget is spent (a single file
/// over the budget is a batch of its own).
fn batch(scope: &Scope, hits: &[Hit], budget: usize) -> Vec<(String, usize)> {
    let mut files: Vec<(usize, usize, String)> = per_file(&scope.root, hits)
        .into_iter()
        .map(|(file, lines)| {
            (
                tier(&file),
                lines.iter().filter(|h| h.line > 0).count(),
                file,
            )
        })
        .filter(|(_, n, file)| *n > 0 && !claimed(scope, file))
        .collect();
    files.sort();
    let mut spent = 0;
    let mut out = Vec::new();
    for (_, n, file) in files {
        if out.is_empty() || spent + n <= budget {
            spent += n;
            out.push((file, n));
        }
        if spent >= budget {
            break;
        }
    }
    out
}

static PARTS: LazyLock<Option<[Regex; 4]>> = LazyLock::new(|| {
    Some([
        Regex::new(r"\]\(([^)\s]+)[^)]*\)|\[\[([^\]|#]+)|(https?://[^\s)>\]]+)").ok()?,
        Regex::new(r#"\b[A-Z]{2,}-\d+\b|\bid="[^"]*"|(?:^|\s)\^[A-Za-z0-9-]+$"#).ok()?,
        Regex::new(r"`[^`]+`").ok()?,
        Regex::new(r"\]\(#([^)]+)\)").ok()?,
    ])
});

/// What a translation must keep.
#[derive(Default)]
struct Structure {
    frontmatter_keys: Vec<String>,
    tags: String,
    headings: Vec<usize>,
    slugs: Vec<String>,
    code_blocks: Vec<String>,
    links: Vec<String>,
    ids: Vec<String>,
    inline_code: Vec<String>,
    table_rows: Vec<usize>,
    fragments: Vec<String>,
}

fn slug(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_'))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

fn structure(text: &str) -> Structure {
    let mut s = Structure::default();
    let Some([links, ids, inline, fragments]) = PARTS.as_ref() else {
        return s;
    };
    let mut frontmatter = text.starts_with("---\n");
    let mut fence: Option<String> = None;
    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let bare = line.trim_end();
        if frontmatter {
            if idx > 0 && bare == "---" {
                frontmatter = false;
            } else if let Some((key, value)) = bare.split_once(':')
                && !key.starts_with(' ')
            {
                s.frontmatter_keys.push(key.to_string());
                if key == "tags" {
                    s.tags = value.trim().to_string();
                }
            }
            continue;
        }
        let start = bare.trim_start();
        let marker = start.starts_with("```") || start.starts_with("~~~");
        if let Some(block) = fence.as_mut() {
            block.push_str(line);
            if marker {
                s.code_blocks.extend(fence.take());
            }
            continue;
        }
        if marker {
            fence = Some(line.to_string());
            continue;
        }
        let level = start.chars().take_while(|c| *c == '#').count();
        if level > 0 && start[level..].starts_with(' ') {
            s.headings.push(level);
            s.slugs.push(slug(start[level..].trim()));
        }
        if start.starts_with('|') {
            s.table_rows
                .push(start.replace("\\|", "").matches('|').count());
        }
        for c in links.captures_iter(bare) {
            if let Some(m) = c.get(1).or_else(|| c.get(2)).or_else(|| c.get(3)) {
                let target = m.as_str().split('#').next().unwrap_or("");
                if !target.is_empty() {
                    s.links.push(target.to_string());
                }
            }
        }
        s.fragments.extend(
            fragments
                .captures_iter(bare)
                .filter_map(|c| c.get(1))
                .map(|m| m.as_str().to_string()),
        );
        s.ids
            .extend(ids.find_iter(bare).map(|m| m.as_str().trim().to_string()));
        s.inline_code
            .extend(inline.find_iter(bare).map(|m| m.as_str().to_string()));
    }
    s.code_blocks.extend(fence);
    // Word order changes between languages; what is cited must survive, not its position.
    s.links.sort();
    s.ids.sort();
    s.inline_code.sort();
    s
}

/// Everything `after` lost compared with `before`, plus the Portuguese it still holds.
fn differences(path: &Path, before: &str, after: &str) -> Vec<String> {
    let (b, a) = (structure(before), structure(after));
    let mut out = Vec::new();
    if path.extension().is_some_and(|e| e == "md") {
        let checks = [
            ("frontmatter keys", b.frontmatter_keys == a.frontmatter_keys),
            ("frontmatter tags", b.tags == a.tags),
            ("heading count and levels", b.headings == a.headings),
            (
                "code blocks (byte-identical)",
                b.code_blocks == a.code_blocks,
            ),
            ("link targets", b.links == a.links),
            ("identifiers and anchors", b.ids == a.ids),
            ("inline code", b.inline_code == a.inline_code),
            ("table rows and columns", b.table_rows == a.table_rows),
        ];
        out.extend(
            checks
                .iter()
                .filter(|(_, same)| !same)
                .map(|(what, _)| format!("changed: {what}")),
        );
        out.extend(
            a.fragments
                .iter()
                .filter(|f| !a.slugs.contains(f))
                .map(|f| format!("broken in-file link: #{f}")),
        );
    }
    out.extend(
        portuguese_lines(path, after)
            .into_iter()
            .map(|(n, l)| format!("Portuguese left, line {n}: {}", l.trim())),
    );
    out
}

#[derive(Default)]
struct Options {
    paths: Vec<PathBuf>,
    init: bool,
    prune: bool,
    lines: bool,
    message: Option<PathBuf>,
    claim: Option<String>,
    budget: Option<usize>,
    file: Option<String>,
    before: Option<PathBuf>,
}

fn parse(args: &[String]) -> Option<(String, Options)> {
    let mut o = Options::default();
    let mut verb = String::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "report" | "next" | "verify" if verb.is_empty() => verb = a.clone(),
            "--path" => o.paths.push(PathBuf::from(it.next()?)),
            "--init" => o.init = true,
            "--prune" => o.prune = true,
            "--lines" => o.lines = true,
            "--message" => o.message = Some(PathBuf::from(it.next()?)),
            "--claim" => o.claim = Some(it.next()?.clone()),
            "--budget" => o.budget = Some(it.next()?.parse().ok()?),
            "--file" => o.file = Some(it.next()?.clone()),
            "--before" => o.before = Some(PathBuf::from(it.next()?)),
            _ => return None,
        }
    }
    if o.paths.is_empty() {
        o.paths.push(PathBuf::from("."));
    }
    Some((verb, o))
}

fn usage() -> i32 {
    eprintln!(
        "usage: stenio language [report] --path <tree>... [--lines] [--init | --prune]\n       stenio language next --path <tree> [--budget <lines>] [--claim <agent>]\n       stenio language verify --path <tree> --file <relative> [--before <original>]\n       stenio language --message <commit-or-PR-text-file>"
    );
    2
}

fn write_ledger(ctx: &Ctx, scope: &Scope, hits: &[Hit], prune: bool) -> i32 {
    let Some(file) = &scope.baseline else {
        eprintln!(
            "language: {} declares no `[language] baseline`",
            scope.root.display()
        );
        return 2;
    };
    if ctx.target != scope.root {
        eprintln!(
            "language: the ledger is written from the tree root: --path {}",
            scope.root.display()
        );
        return 2;
    }
    let old = read_baseline(file);
    if prune == old.is_none() {
        let why = if prune {
            "does not exist (use --init)"
        } else {
            "already exists (only --prune may change it)"
        };
        eprintln!("language: {} {why}", file.display());
        return 2;
    }
    match fs::write(file, render(&scope.root, hits, old.as_ref())) {
        Ok(()) => {
            println!("language: wrote {}", file.display());
            0
        }
        Err(e) => {
            eprintln!("language: cannot write {}: {e}", file.display());
            2
        }
    }
}

fn report(o: &Options) -> i32 {
    for path in &o.paths {
        let ctx = Ctx::new(path, None);
        for (scope, hits) in collect(&ctx).values() {
            println!("{}", summary(scope, hits));
            for (file, lines) in per_file(&scope.root, hits) {
                println!("  {:>6}  {}  {file}", lines.len(), TIERS[tier(&file)]);
                if o.lines {
                    for h in lines {
                        println!("          {}: {}", h.line, h.text.trim());
                    }
                }
            }
            if (o.init || o.prune) && scope.root == ctx.target {
                let code = write_ledger(&ctx, scope, hits, o.prune);
                if code != 0 {
                    return code;
                }
            }
        }
    }
    0
}

fn next(o: &Options) -> i32 {
    let ctx = Ctx::new(&o.paths[0], None);
    for (scope, hits) in collect(&ctx).values() {
        for (file, lines) in batch(scope, hits, o.budget.unwrap_or(DEFAULT_BUDGET)) {
            if let Some(agent) = &o.claim {
                match claim(scope, &file, agent) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(e) => {
                        eprintln!("language: cannot claim {file}: {e}");
                        return 2;
                    }
                }
            }
            println!(
                "{lines:>6}  {}  {}",
                TIERS[tier(&file)],
                scope.root.join(&file).display()
            );
        }
    }
    0
}

fn verify(o: &Options) -> i32 {
    let ctx = Ctx::new(&o.paths[0], None);
    let Some(rel) = o.file.as_deref() else {
        return usage();
    };
    let found = collect(&ctx);
    let Some((scope, hits)) = found.values().find(|(s, _)| s.root == ctx.target) else {
        eprintln!("language: --path must be the root of the tree");
        return 2;
    };
    let file = scope.root.join(rel);
    let original = o
        .before
        .as_ref()
        .and_then(|p| fs::read_to_string(p).ok())
        .or_else(|| fs::read_to_string(claim_file(scope, rel, "orig")).ok())
        .or_else(|| git(&scope.root, &["show", &format!("HEAD:./{rel}")]));
    let (Some(before), Ok(after)) = (original, fs::read_to_string(&file)) else {
        eprintln!("language: need the translated file and its original (--before, a claim or git)");
        return 2;
    };
    let problems = differences(&file, &before, &after);
    if !problems.is_empty() {
        for p in &problems {
            println!("FAIL {rel}: {p}");
        }
        return 1;
    }
    println!("PASS {rel}: structure kept, no Portuguese left");
    for kind in ["claim", "orig"] {
        let mark = claim_file(scope, rel, kind);
        if mark.exists()
            && let Err(e) = fs::remove_file(&mark)
        {
            eprintln!("language: cannot release {}: {e}", mark.display());
        }
    }
    if let Err(e) = fs::remove_dir(claim_dir(scope))
        && e.kind() != std::io::ErrorKind::NotFound
        && e.kind() != std::io::ErrorKind::DirectoryNotEmpty
    {
        eprintln!("language: claim directory kept: {e}");
    }
    if scope.baseline.is_some() {
        return write_ledger(&ctx, scope, hits, true);
    }
    0
}

/// `stenio language ...`.
pub fn run_cli(args: &[String]) -> i32 {
    let Some((verb, o)) = parse(args) else {
        return usage();
    };
    if let Some(file) = &o.message {
        return judge_message(file);
    }
    match verb.as_str() {
        "next" => next(&o),
        "verify" => verify(&o),
        _ => report(&o),
    }
}

/// Mutation proofs of `verify` and of the ledger ratchet.
pub fn self_test_cases() -> Vec<(String, bool)> {
    const BEFORE: &str = "---\ntags: [doc]\n---\n# Guia\n\n[ir](#guia) HB-001 `ls` [x](a.md)\n\n```sh\n# nao mexer\n```\n\n| a | b |\n";
    const AFTER: &str = "---\ntags: [doc]\n---\n# Guide\n\n[go](#guide) HB-001 `ls` [x](a.md)\n\n```sh\n# nao mexer\n```\n\n| a | b |\n";
    let check = |name: &str, after: String, expected: bool| {
        let clean = differences(Path::new("a.md"), BEFORE, &after).is_empty();
        (format!("LANG-VERIFY {name}"), clean == expected)
    };
    let broken = [
        ("heading-lost", "# Guide\n", "Guide\n"),
        ("code-changed", "# nao mexer", "# do not touch"),
        ("link-lost", "(a.md)", "(b.md)"),
        ("id-lost", "HB-001", "HB-002"),
        ("table-changed", "| a | b |", "| a |"),
        ("tags-changed", "[doc]", "[docs]"),
        ("anchor-broken", "(#guide)", "(#guia)"),
        ("portuguese-left", "[go]", "Falta conferir [go]"),
    ];
    let mut out = vec![check("faithful", AFTER.to_string(), true)];
    out.extend(
        broken
            .iter()
            .map(|(name, from, to)| check(name, AFTER.replacen(from, to, 1), false)),
    );
    let hit = |text: &str| Hit {
        path: PathBuf::from("/t/a.md"),
        line: 1,
        text: text.to_string(),
    };
    let kept = HashMap::from([(line_hash("old"), 1)]);
    let pruned = render(
        Path::new("/t"),
        &[hit("old"), hit("old"), hit("new")],
        Some(&kept),
    );
    out.push((
        "LANG-LEDGER prune-never-grows".to_string(),
        pruned.contains("total lines=1 files=1") && pruned.lines().count() == 4,
    ));
    out
}
