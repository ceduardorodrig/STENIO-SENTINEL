//! `stenio redact` (GB-184): keeps stored secret values out of tool output, transcripts and session
//! databases. As a filter it replaces every stored value of stdin with `[REDACTED:NAME]` (exit 3
//! when it had to); with `--scan` it fails naming the file and variable that already hold a value.
//! Matching is exact bytes against the store, so it catches keys no prefix pattern knows.

use super::store::{Store, load};
use clap::Parser;
use ignore::WalkBuilder;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about = "Redact stored secret values from a stream, or find them in files")]
struct Args {
    #[arg(
        long,
        help = "Env or sops store whose values must not appear (repeatable)"
    )]
    store: Vec<PathBuf>,
    #[arg(long, help = "Decrypt sops stores in memory")]
    decrypt: bool,
    #[arg(
        long,
        help = "Scan these files or directories instead of filtering stdin"
    )]
    scan: Vec<PathBuf>,
    #[arg(long, help = "Tool name for the warning")]
    tool: Option<String>,
    #[arg(long, default_value_t = 8, help = "Ignore values shorter than this")]
    min_len: usize,
}

/// `(name, secret bytes)`, longest first so a value inside a longer one never splits it.
fn needles(stores: &[Store], min_len: usize) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (name, value) in stores.iter().flat_map(|s| &s.entries) {
        if value.starts_with("ENC[") {
            continue;
        }
        // `scheme://user:password@host` carries the password even under a neutral name.
        let url_password = value
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('@'))
            .and_then(|(auth, _)| auth.split_once(':'))
            .map(|(_, p)| p);
        let whole = (crate::infra::key_looks_secret(name) || url_password.is_some())
            .then_some(value.as_str());
        for v in whole.into_iter().chain(url_password) {
            if v.len() >= min_len && !v.starts_with(['/', '$']) {
                out.push((name.clone(), v.as_bytes().to_vec()));
            }
        }
    }
    out.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let mut from = 0;
    while let Some(i) = hay.get(from..)?.iter().position(|b| *b == first) {
        let at = from + i;
        if hay[at..].starts_with(needle) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// The text with every needle replaced, and `(name, replacements)`.
fn redact(input: &[u8], needles: &[(String, Vec<u8>)]) -> (Vec<u8>, Vec<(String, usize)>) {
    let mut text = input.to_vec();
    let mut hits = Vec::new();
    for (name, needle) in needles {
        let marker = format!("[REDACTED:{name}]");
        let mut out = Vec::with_capacity(text.len());
        let mut rest = text.as_slice();
        let mut n = 0usize;
        while let Some(at) = find(rest, needle) {
            out.extend_from_slice(&rest[..at]);
            out.extend_from_slice(marker.as_bytes());
            rest = &rest[at + needle.len()..];
            n += 1;
        }
        out.extend_from_slice(rest);
        if n > 0 {
            hits.push((name.clone(), n));
            text = out;
        }
    }
    (text, hits)
}

/// One `FAIL` line per `(file, variable)`; SQLite files are searched as raw bytes.
fn scan(paths: &[PathBuf], needles: &[(String, Vec<u8>)]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for root in paths {
        if !root.exists() {
            return Err(format!("{} does not exist", root.display()));
        }
        let mut walker = WalkBuilder::new(root);
        walker.standard_filters(false);
        for entry in walker.build().flatten() {
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let bytes = std::fs::read(entry.path())
                .map_err(|e| format!("cannot read {}: {}", entry.path().display(), e.kind()))?;
            for (name, needle) in needles {
                if find(&bytes, needle).is_some() {
                    out.push(format!(
                        "FAIL SECRET-IN-AGENT-OUTPUT {}: value of {name}",
                        entry.path().display()
                    ));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn run(args: &Args) -> Result<i32, String> {
    let stores = args
        .store
        .iter()
        .map(|p| load(p, args.decrypt))
        .collect::<Result<Vec<_>, _>>()?;
    if stores.iter().any(|s| s.encrypted) {
        return Err("a store is encrypted, pass --decrypt".to_string());
    }
    let needles = needles(&stores, args.min_len);
    if needles.is_empty() {
        return Err("no secret value loaded from --store".to_string());
    }
    if !args.scan.is_empty() {
        let fails = scan(&args.scan, &needles)?;
        for l in &fails {
            println!("{l}");
        }
        let verdict = if fails.is_empty() { "PASS" } else { "FAIL" };
        println!("stenio: {verdict} redact-scan fails={}", fails.len());
        return Ok(i32::from(!fails.is_empty()));
    }
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| format!("stdin: {}", e.kind()))?;
    let (text, hits) = redact(&input, &needles);
    std::io::stdout()
        .write_all(&text)
        .map_err(|e| format!("stdout: {}", e.kind()))?;
    for (name, n) in &hits {
        eprintln!(
            "stenio: WARN redacted {name} x{n} from {}",
            args.tool.as_deref().unwrap_or("tool output")
        );
    }
    Ok(if hits.is_empty() { 0 } else { 3 })
}

/// Exit 2 means nothing was filtered: a caller must drop the output, never pass it through.
pub fn run_cli(argv: &[String]) -> i32 {
    let args = match Args::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            return crate::util::usage_exit(&e);
        }
    };
    run(&args).unwrap_or_else(|e| {
        eprintln!("stenio: redact {e}");
        2
    })
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let v = super::dumps::FAKE_VALUE;
    let store = super::store::parse(&format!(
        "PROVIDER_API_KEY={v}\nDATABASE_URL=postgres://u:Pw{v}@db/x\nSMTP_HOST=smtp.invalid.test\n"
    ));
    let n = needles(std::slice::from_ref(&store), 8);
    let (clean, hits) = redact(
        format!("k={v} p=Pw{v} h=smtp.invalid.test\n").as_bytes(),
        &n,
    );
    let clean = String::from_utf8_lossy(&clean).into_owned();
    let d = super::fixture(
        "redact",
        &[
            ("state.db", &format!("\u{0}\u{1}{v}\u{0}")),
            ("ok.log", "fine"),
        ],
    );
    let found = scan(std::slice::from_ref(&d), &n)
        .unwrap_or_default()
        .join("\n");
    let _ = std::fs::remove_dir_all(&d);
    let line = format!("PROVIDER_API_KEY={v}");
    let echoed = crate::guardian::scan_content_for_secrets(std::path::Path::new("x.env"), &line);
    let enc = super::fixture("redact-enc", &[("bad.enc.env", &format!("{line}\n"))]);
    let unencrypted = crate::infra::audit_infrastructure(&enc, false).violations;
    let _ = std::fs::remove_dir_all(&enc);
    vec![
        (
            "redact: engine findings never echo a value".to_string(),
            !echoed.is_empty()
                && !unencrypted.is_empty()
                && echoed
                    .iter()
                    .chain(&unencrypted)
                    .all(|f| !f.snippet.contains(&v[..6])),
        ),
        (
            "redact: mutation, stored values replaced and named".to_string(),
            !clean.contains(v)
                && clean.contains("k=[REDACTED:PROVIDER_API_KEY]")
                && clean.contains("[REDACTED:DATABASE_URL]")
                && clean.contains("h=smtp.invalid.test")
                && hits.len() == 2,
        ),
        (
            "redact: clean text untouched".to_string(),
            redact(b"nothing here", &n) == (b"nothing here".to_vec(), Vec::new()),
        ),
        (
            "redact scan: mutation, value inside a binary db names file and variable".to_string(),
            found.contains("state.db: value of PROVIDER_API_KEY")
                && !found.contains("ok.log")
                && !found.contains(v),
        ),
    ]
}
