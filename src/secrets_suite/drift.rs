//! `stenio secrets-drift` (GB-177): the master env, the encrypted store, each host mirror and each
//! live consumer must describe the same keys. Names are compared always; values only between two
//! files of the same form (both plaintext, which includes `--decrypt`, or byte-identical copies of
//! one sops file). The report names keys and hosts, never a value or a hash.

use super::store::{Store, labelled, load};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about = "Compare secret key names and values across stores (never prints a value)")]
struct Args {
    #[arg(long, help = "The reference encrypted store (the vault copy)")]
    store: PathBuf,
    #[arg(long, help = "Plaintext master env file")]
    master: Option<PathBuf>,
    #[arg(long, value_name = "HOST=PATH", help = "Host copy of the store")]
    mirror: Vec<String>,
    #[arg(
        long,
        value_name = "LABEL=PATH",
        help = "Env file of a live consumer: every key it names must be in the store"
    )]
    consumer: Vec<String>,
    #[arg(long, help = "Key a consumer needs (repeatable)")]
    require: Vec<String>,
    #[arg(long, help = "Decrypt sops files in memory to compare values")]
    decrypt: bool,
}

fn name_drift(out: &mut Vec<String>, a: &str, left: &Store, b: &str, right: &Store) {
    for k in left.entries.keys() {
        if !right.entries.contains_key(k) {
            out.push(format!("FAIL key {k}: in {a}, missing from {b}"));
        }
    }
    for k in right.entries.keys() {
        if !left.entries.contains_key(k) {
            out.push(format!("FAIL key {k}: in {b}, missing from {a}"));
        }
    }
}

/// Returns `false` when the two forms cannot be compared by value.
fn value_drift(out: &mut Vec<String>, a: &str, left: &Store, b: &str, right: &Store) -> bool {
    if left.encrypted != right.encrypted {
        return false;
    }
    for (k, v) in &left.entries {
        if right.entries.get(k).is_some_and(|w| w != v) {
            let how = if left.encrypted {
                "ciphertext differs (stale or re-encrypted copy)"
            } else {
                "value differs"
            };
            out.push(format!("FAIL key {k}: {how} between {a} and {b}"));
        }
    }
    true
}

/// `(report lines, failures, notes)`.
fn compare(args: &Args) -> Result<(Vec<String>, Vec<String>), String> {
    let reference = load(&args.store, args.decrypt)?;
    if reference.entries.is_empty() {
        return Err("the reference store holds no key".to_string());
    }
    let mut fails = Vec::new();
    let mut notes = Vec::new();
    if let Some(path) = &args.master {
        let master = load(path, args.decrypt)?;
        name_drift(&mut fails, "master", &master, "store", &reference);
        if !value_drift(&mut fails, "master", &master, "store", &reference) {
            notes.push("note: master and store values not compared (use --decrypt)".to_string());
        }
    }
    for spec in &args.mirror {
        let (host, path) = labelled(spec)?;
        let mirror = load(&path, args.decrypt)?;
        let label = format!("mirror {host}");
        if let (Some(m), Some(r)) = (&mirror.last_modified, &reference.last_modified)
            && m < r
        {
            fails.push(format!(
                "FAIL {label}: stale, sops_lastmodified {m} is older than the store {r}"
            ));
        }
        name_drift(&mut fails, "store", &reference, &label, &mirror);
        if !value_drift(&mut fails, "store", &reference, &label, &mirror) {
            notes.push(format!("note: {label} values not compared (use --decrypt)"));
        }
    }
    for spec in &args.consumer {
        let (label, path) = labelled(spec)?;
        for k in load(&path, false)?.entries.keys() {
            if !reference.entries.contains_key(k) {
                fails.push(format!(
                    "FAIL key {k}: needed by consumer {label}, missing from store"
                ));
            }
        }
    }
    for k in &args.require {
        if !reference.entries.contains_key(k) {
            fails.push(format!("FAIL key {k}: required, missing from store"));
        }
    }
    Ok((fails, notes))
}

pub fn run_cli(argv: &[String]) -> i32 {
    let args = match Args::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            return crate::util::usage_exit(&e);
        }
    };
    match compare(&args) {
        Ok((fails, notes)) => {
            for l in notes.iter().chain(&fails) {
                println!("{l}");
            }
            if !fails.is_empty() {
                println!("stenio: FAIL secrets-drift fails={}", fails.len());
            }
            i32::from(!fails.is_empty())
        }
        Err(e) => {
            eprintln!("stenio: secrets-drift {e}");
            2
        }
    }
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let enc = |when: &str, keys: &[&str]| {
        let body: String = keys
            .iter()
            .map(|k| format!("{k}=ENC[AES256_GCM,data:{k}{when},type:str]\n"))
            .collect();
        format!("{body}sops_lastmodified={when}\nsops_version=3.9.0\n")
    };
    let new = enc("2026-11-05T10:00:00Z", &["A_KEY", "B_KEY"]);
    let old = enc("2026-10-13T10:00:00Z", &["A_KEY"]);
    let d = super::fixture(
        "drift",
        &[
            ("store.env", &new),
            ("same.env", &new),
            ("old.env", &old),
            ("master.env", "A_KEY=fakeone\nB_KEY=faketwo\n"),
            ("short.env", "A_KEY=fakeone\n"),
            ("plain.env", "A_KEY=fakeone\nB_KEY=fakeCHANGED\n"),
            ("app.env", "export C_KEY=x\n"),
        ],
    );
    let p = |n: &str| d.join(n).display().to_string();
    let run = |extra: &[(&str, String)], store: &str| {
        let mut argv = vec!["d".to_string(), "--store".to_string(), p(store)];
        for (flag, value) in extra {
            argv.push((*flag).to_string());
            argv.push(value.clone());
        }
        Args::try_parse_from(argv)
            .ok()
            .and_then(|a| compare(&a).ok())
            .map(|(f, _)| f.join("\n"))
    };
    let consistent = run(
        &[
            ("--master", p("master.env")),
            ("--mirror", format!("kavure={}", p("same.env"))),
        ],
        "store.env",
    );
    let short = run(&[("--master", p("short.env"))], "store.env");
    let stale = run(
        &[("--mirror", format!("kavure={}", p("old.env")))],
        "store.env",
    );
    let value = run(&[("--master", p("plain.env"))], "master.env");
    let consumer = run(
        &[("--consumer", format!("hermes={}", p("app.env")))],
        "store.env",
    );
    let _ = std::fs::remove_dir_all(&d);
    let has = |r: &Option<String>, n: &str| r.as_deref().is_some_and(|s| s.contains(n));
    vec![
        (
            "secrets-drift: consistent fleet is silent".to_string(),
            consistent.as_deref() == Some(""),
        ),
        (
            "secrets-drift: mutation, key removed from master names it".to_string(),
            has(&short, "key B_KEY: in store, missing from master"),
        ),
        (
            "secrets-drift: mutation, stale mirror names host and key".to_string(),
            has(&stale, "mirror kavure: stale")
                && has(&stale, "key B_KEY: in store, missing from mirror kavure"),
        ),
        (
            "secrets-drift: mutation, changed value named without the value".to_string(),
            has(&value, "key B_KEY: value differs") && !has(&value, "fake"),
        ),
        (
            "secrets-drift: consumer key absent from store fails".to_string(),
            has(&consumer, "key C_KEY: needed by consumer hermes"),
        ),
    ]
}
